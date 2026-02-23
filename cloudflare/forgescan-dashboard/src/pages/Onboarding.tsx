import { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Rocket,
  ShieldCheck,
  Cpu,
  Zap,
  CheckCircle2,
  Circle,
  ArrowRight,
  ArrowLeft,
  Loader2,
  Globe,
  Server,
  Upload,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useApi } from '@/hooks/useApi';
import { onboardingApi } from '@/lib/api';

const STEPS = [
  { id: 'welcome', title: 'Welcome', icon: Rocket, description: 'Get started with ForgeScan 360' },
  { id: 'compliance', title: 'Compliance', icon: ShieldCheck, description: 'Initialize compliance frameworks' },
  { id: 'scanner', title: 'Scanner', icon: Cpu, description: 'Connect your first scanner' },
  { id: 'scan', title: 'Quick Scan', icon: Zap, description: 'Run your first vulnerability scan' },
  { id: 'done', title: 'Ready', icon: CheckCircle2, description: 'You\'re all set' },
];

export function Onboarding() {
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState(0);
  const [target, setTarget] = useState('');
  const [seedLoading, setSeedLoading] = useState(false);
  const [seedDone, setSeedDone] = useState(false);
  const [seedResult, setSeedResult] = useState<{ frameworks: number; controls: number } | null>(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanDone, setScanDone] = useState(false);
  const [scanResult, setScanResult] = useState<{ scan_id: string; message: string } | null>(null);
  const [error, setError] = useState('');

  const fetchStatus = useCallback(() => onboardingApi.getStatus(), []);
  const { data: status } = useApi(fetchStatus);

  // Auto-advance past completed steps
  useEffect(() => {
    if (status) {
      if (status.steps.compliance_seeded) setSeedDone(true);
      if (status.steps.first_scan_run) setScanDone(true);
    }
  }, [status]);

  const handleSeedCompliance = async () => {
    setSeedLoading(true);
    setError('');
    try {
      const result = await onboardingApi.seedCompliance();
      setSeedDone(true);
      setSeedResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to seed compliance frameworks');
    } finally {
      setSeedLoading(false);
    }
  };

  const handleQuickScan = async () => {
    if (!target.trim()) {
      setError('Please enter a target IP address, CIDR range, or hostname');
      return;
    }
    setScanLoading(true);
    setError('');
    try {
      const result = await onboardingApi.quickScan(target.trim());
      setScanDone(true);
      setScanResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan');
    } finally {
      setScanLoading(false);
    }
  };

  const next = () => setCurrentStep((s) => Math.min(s + 1, STEPS.length - 1));
  const prev = () => setCurrentStep((s) => Math.max(s - 1, 0));

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6" style={{ background: 'linear-gradient(135deg, #060f1a 0%, #091e36 50%, #0F2A4A 100%)' }}>
      <div className="w-full max-w-2xl">
        {/* Header */}
        <div className="text-center mb-8">
          <img src="/forge-logo-400.png" alt="Forge Cyber Defense" className="mx-auto w-40 h-auto mb-2" draggable={false} />
          <h1 className="text-2xl font-bold text-white">Welcome to ForgeScan 360</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Let's get your security platform up and running in under 30 minutes
          </p>
        </div>

        {/* Progress Steps */}
        <div className="flex items-center justify-center gap-2 mb-8">
          {STEPS.map((step, i) => {
            const isActive = i === currentStep;
            const isCompleted = i < currentStep;
            return (
              <div key={step.id} className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentStep(i)}
                  className="flex items-center gap-1.5 transition-all"
                  style={{ opacity: isActive ? 1 : isCompleted ? 0.8 : 0.4 }}
                >
                  {isCompleted ? (
                    <CheckCircle2 className="h-5 w-5 text-teal-400" />
                  ) : isActive ? (
                    <div className="h-5 w-5 rounded-full border-2 border-teal-400 flex items-center justify-center">
                      <div className="h-2 w-2 rounded-full bg-teal-400" />
                    </div>
                  ) : (
                    <Circle className="h-5 w-5 text-muted-foreground" />
                  )}
                  <span className={`text-xs font-medium hidden sm:inline ${isActive ? 'text-white' : 'text-muted-foreground'}`}>
                    {step.title}
                  </span>
                </button>
                {i < STEPS.length - 1 && (
                  <div className="w-8 h-px" style={{ background: isCompleted ? '#14b8a6' : 'rgba(75,119,169,0.3)' }} />
                )}
              </div>
            );
          })}
        </div>

        {/* Step Content */}
        <Card className="border-[rgba(75,119,169,0.3)]" style={{ background: 'rgba(9,30,54,0.9)', backdropFilter: 'blur(20px)' }}>
          <CardContent className="p-8">
            {/* Step 0: Welcome */}
            {currentStep === 0 && (
              <div className="text-center space-y-6">
                <div className="inline-flex h-16 w-16 items-center justify-center rounded-2xl bg-teal-500/10 border border-teal-500/20">
                  <Rocket className="h-8 w-8 text-teal-400" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">Let's Set Up Your Security Platform</h2>
                  <p className="text-sm text-muted-foreground mt-2 max-w-md mx-auto">
                    This wizard will guide you through four quick steps to get ForgeScan 360 operational:
                    compliance frameworks, scanner deployment, and your first vulnerability scan.
                  </p>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-left">
                  <div className="rounded-lg p-3 border border-[rgba(75,119,169,0.2)]" style={{ background: 'rgba(255,255,255,0.03)' }}>
                    <ShieldCheck className="h-5 w-5 text-teal-400 mb-2" />
                    <p className="text-sm font-medium text-white">Compliance</p>
                    <p className="text-xs text-muted-foreground">NIST, CIS, PCI-DSS, HIPAA frameworks pre-loaded</p>
                  </div>
                  <div className="rounded-lg p-3 border border-[rgba(75,119,169,0.2)]" style={{ background: 'rgba(255,255,255,0.03)' }}>
                    <Cpu className="h-5 w-5 text-teal-400 mb-2" />
                    <p className="text-sm font-medium text-white">Scanners</p>
                    <p className="text-xs text-muted-foreground">Deploy a scanner or import existing data</p>
                  </div>
                  <div className="rounded-lg p-3 border border-[rgba(75,119,169,0.2)]" style={{ background: 'rgba(255,255,255,0.03)' }}>
                    <Zap className="h-5 w-5 text-teal-400 mb-2" />
                    <p className="text-sm font-medium text-white">Quick Scan</p>
                    <p className="text-xs text-muted-foreground">One-click network + config audit on any CIDR</p>
                  </div>
                </div>

                {status && (
                  <div className="rounded-lg p-3 border border-[rgba(75,119,169,0.2)] text-left" style={{ background: 'rgba(255,255,255,0.02)' }}>
                    <p className="text-xs font-medium text-muted-foreground mb-2">Current Setup Progress</p>
                    <div className="h-2 rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full rounded-full bg-teal-500 transition-all"
                        style={{ width: `${(status.completed / status.total) * 100}%` }}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {status.completed}/{status.total} steps complete
                    </p>
                  </div>
                )}

                <Button onClick={next} className="gap-2">
                  Get Started <ArrowRight className="h-4 w-4" />
                </Button>
              </div>
            )}

            {/* Step 1: Compliance Seed */}
            {currentStep === 1 && (
              <div className="space-y-6">
                <div className="text-center">
                  <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-teal-500/10 border border-teal-500/20 mb-3">
                    <ShieldCheck className="h-7 w-7 text-teal-400" />
                  </div>
                  <h2 className="text-lg font-bold text-white">Initialize Compliance Frameworks</h2>
                  <p className="text-sm text-muted-foreground mt-1">
                    Pre-load industry-standard compliance frameworks with all controls and mappings.
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  {[
                    { name: 'NIST 800-53 Rev. 5', controls: 25, desc: 'Federal security controls' },
                    { name: 'CIS Controls v8', controls: 15, desc: 'Critical security controls' },
                    { name: 'PCI DSS v4.0', controls: 12, desc: 'Payment card security' },
                    { name: 'HIPAA Security', controls: 10, desc: 'Healthcare data protection' },
                  ].map((fw) => (
                    <div key={fw.name} className="rounded-lg p-3 border border-[rgba(75,119,169,0.2)]" style={{ background: 'rgba(255,255,255,0.03)' }}>
                      <p className="text-sm font-medium text-white">{fw.name}</p>
                      <p className="text-xs text-muted-foreground">{fw.controls} controls - {fw.desc}</p>
                    </div>
                  ))}
                </div>

                {seedDone ? (
                  <div className="rounded-lg p-4 border border-teal-500/30 bg-teal-500/5 text-center">
                    <CheckCircle2 className="h-6 w-6 text-teal-400 mx-auto mb-2" />
                    <p className="text-sm font-medium text-teal-400">Compliance frameworks loaded</p>
                    {seedResult && (
                      <p className="text-xs text-muted-foreground mt-1">
                        {seedResult.frameworks} frameworks, {seedResult.controls} controls
                      </p>
                    )}
                  </div>
                ) : (
                  <Button onClick={handleSeedCompliance} disabled={seedLoading} className="w-full gap-2">
                    {seedLoading ? (
                      <><Loader2 className="h-4 w-4 animate-spin" /> Loading frameworks...</>
                    ) : (
                      <><ShieldCheck className="h-4 w-4" /> Initialize All Frameworks</>
                    )}
                  </Button>
                )}

                {error && (
                  <div className="rounded-md bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
                )}
              </div>
            )}

            {/* Step 2: Scanner Setup */}
            {currentStep === 2 && (
              <div className="space-y-6">
                <div className="text-center">
                  <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-teal-500/10 border border-teal-500/20 mb-3">
                    <Cpu className="h-7 w-7 text-teal-400" />
                  </div>
                  <h2 className="text-lg font-bold text-white">Deploy a Scanner</h2>
                  <p className="text-sm text-muted-foreground mt-1">
                    Choose how to get vulnerability data into ForgeScan.
                  </p>
                </div>

                <div className="space-y-3">
                  <button
                    onClick={() => navigate('/admin/scanners')}
                    className="w-full text-left rounded-lg p-4 border border-[rgba(75,119,169,0.2)] hover:border-teal-500/30 transition-colors"
                    style={{ background: 'rgba(255,255,255,0.03)' }}
                  >
                    <div className="flex items-start gap-3">
                      <Server className="h-5 w-5 text-teal-400 mt-0.5" />
                      <div>
                        <p className="text-sm font-medium text-white">Register a Scanner Agent</p>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Deploy the ForgeScan agent on your network. It polls for tasks, executes scans, and reports findings automatically.
                        </p>
                      </div>
                      <ArrowRight className="h-4 w-4 text-muted-foreground ml-auto mt-0.5" />
                    </div>
                  </button>

                  <button
                    onClick={() => navigate('/import')}
                    className="w-full text-left rounded-lg p-4 border border-[rgba(75,119,169,0.2)] hover:border-teal-500/30 transition-colors"
                    style={{ background: 'rgba(255,255,255,0.03)' }}
                  >
                    <div className="flex items-start gap-3">
                      <Upload className="h-5 w-5 text-blue-400 mt-0.5" />
                      <div>
                        <p className="text-sm font-medium text-white">Import Existing Scan Data</p>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Import findings from Tenable, Qualys, Rapid7, or upload SARIF/CycloneDX/CSV files from your existing tools.
                        </p>
                      </div>
                      <ArrowRight className="h-4 w-4 text-muted-foreground ml-auto mt-0.5" />
                    </div>
                  </button>

                  <button
                    onClick={() => navigate('/integrations')}
                    className="w-full text-left rounded-lg p-4 border border-[rgba(75,119,169,0.2)] hover:border-teal-500/30 transition-colors"
                    style={{ background: 'rgba(255,255,255,0.03)' }}
                  >
                    <div className="flex items-start gap-3">
                      <Globe className="h-5 w-5 text-orange-400 mt-0.5" />
                      <div>
                        <p className="text-sm font-medium text-white">Connect Cloud Accounts</p>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Link AWS, Azure, or GCP accounts for continuous cloud security posture monitoring.
                        </p>
                      </div>
                      <ArrowRight className="h-4 w-4 text-muted-foreground ml-auto mt-0.5" />
                    </div>
                  </button>
                </div>

                <p className="text-center text-xs text-muted-foreground">
                  You can also skip this step and configure scanners later from the Admin panel.
                </p>
              </div>
            )}

            {/* Step 3: Quick Scan */}
            {currentStep === 3 && (
              <div className="space-y-6">
                <div className="text-center">
                  <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-teal-500/10 border border-teal-500/20 mb-3">
                    <Zap className="h-7 w-7 text-teal-400" />
                  </div>
                  <h2 className="text-lg font-bold text-white">Run Your First Quick Scan</h2>
                  <p className="text-sm text-muted-foreground mt-1">
                    Enter a CIDR range or hostname to run a network + configuration audit.
                  </p>
                </div>

                {scanDone ? (
                  <div className="rounded-lg p-4 border border-teal-500/30 bg-teal-500/5 text-center space-y-3">
                    <CheckCircle2 className="h-8 w-8 text-teal-400 mx-auto" />
                    <div>
                      <p className="text-sm font-medium text-teal-400">Scan launched successfully</p>
                      {scanResult && (
                        <p className="text-xs text-muted-foreground mt-1">{scanResult.message}</p>
                      )}
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate('/scans')}
                      className="gap-2"
                    >
                      View Scan Progress <ArrowRight className="h-3 w-3" />
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="target">Target</Label>
                      <Input
                        id="target"
                        placeholder="e.g., 192.168.1.0/24 or example.com"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        disabled={scanLoading}
                      />
                      <p className="text-xs text-muted-foreground">
                        Scans common ports (1-1024 + database + web), detects services, and checks for vulnerabilities.
                      </p>
                    </div>

                    <div className="rounded-lg p-3 border border-[rgba(75,119,169,0.2)] space-y-1" style={{ background: 'rgba(255,255,255,0.02)' }}>
                      <p className="text-xs font-medium text-muted-foreground">Quick Scan includes:</p>
                      <ul className="text-xs text-muted-foreground space-y-0.5">
                        <li className="flex items-center gap-1.5"><CheckCircle2 className="h-3 w-3 text-teal-400" /> Network discovery</li>
                        <li className="flex items-center gap-1.5"><CheckCircle2 className="h-3 w-3 text-teal-400" /> Port scanning (1-1024 + common services)</li>
                        <li className="flex items-center gap-1.5"><CheckCircle2 className="h-3 w-3 text-teal-400" /> Service detection and fingerprinting</li>
                        <li className="flex items-center gap-1.5"><CheckCircle2 className="h-3 w-3 text-teal-400" /> Vulnerability check against CVE database</li>
                      </ul>
                    </div>

                    <Button
                      onClick={handleQuickScan}
                      disabled={scanLoading || !target.trim()}
                      className="w-full gap-2"
                    >
                      {scanLoading ? (
                        <><Loader2 className="h-4 w-4 animate-spin" /> Starting scan...</>
                      ) : (
                        <><Zap className="h-4 w-4" /> Launch Quick Scan</>
                      )}
                    </Button>
                  </div>
                )}

                {error && (
                  <div className="rounded-md bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
                )}
              </div>
            )}

            {/* Step 4: Done */}
            {currentStep === 4 && (
              <div className="text-center space-y-6">
                <div className="inline-flex h-16 w-16 items-center justify-center rounded-2xl bg-teal-500/10 border border-teal-500/20">
                  <CheckCircle2 className="h-8 w-8 text-teal-400" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">You're All Set!</h2>
                  <p className="text-sm text-muted-foreground mt-2 max-w-md mx-auto">
                    ForgeScan 360 is ready. Your Executive Dashboard will show risk grades, MTTR metrics, and SLA compliance as findings flow in.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-left">
                  <button
                    onClick={() => navigate('/')}
                    className="rounded-lg p-4 border border-teal-500/20 hover:border-teal-500/40 transition-colors text-left"
                    style={{ background: 'rgba(20,184,166,0.05)' }}
                  >
                    <p className="text-sm font-medium text-white">Go to Dashboard</p>
                    <p className="text-xs text-muted-foreground mt-0.5">View your executive risk scorecard</p>
                  </button>
                  <button
                    onClick={() => navigate('/scans')}
                    className="rounded-lg p-4 border border-[rgba(75,119,169,0.2)] hover:border-teal-500/30 transition-colors text-left"
                    style={{ background: 'rgba(255,255,255,0.03)' }}
                  >
                    <p className="text-sm font-medium text-white">View Scans</p>
                    <p className="text-xs text-muted-foreground mt-0.5">Monitor your running scans</p>
                  </button>
                  <button
                    onClick={() => navigate('/redops')}
                    className="rounded-lg p-4 border border-[rgba(75,119,169,0.2)] hover:border-teal-500/30 transition-colors text-left"
                    style={{ background: 'rgba(255,255,255,0.03)' }}
                  >
                    <p className="text-sm font-medium text-white">Launch RedOps</p>
                    <p className="text-xs text-muted-foreground mt-0.5">Run AI-powered penetration testing</p>
                  </button>
                  <button
                    onClick={() => navigate('/compliance')}
                    className="rounded-lg p-4 border border-[rgba(75,119,169,0.2)] hover:border-teal-500/30 transition-colors text-left"
                    style={{ background: 'rgba(255,255,255,0.03)' }}
                  >
                    <p className="text-sm font-medium text-white">Compliance</p>
                    <p className="text-xs text-muted-foreground mt-0.5">Review gap analysis against frameworks</p>
                  </button>
                </div>
              </div>
            )}

            {/* Navigation Buttons */}
            <div className="flex items-center justify-between mt-8 pt-4 border-t border-[rgba(75,119,169,0.2)]">
              <Button
                variant="ghost"
                onClick={prev}
                disabled={currentStep === 0}
                className="gap-2"
              >
                <ArrowLeft className="h-4 w-4" /> Back
              </Button>

              <div className="flex gap-2">
                {currentStep > 0 && currentStep < 4 && (
                  <Button variant="ghost" onClick={next} className="text-muted-foreground">
                    Skip
                  </Button>
                )}
                {currentStep > 0 && currentStep < 4 && (
                  <Button onClick={next} className="gap-2">
                    Next <ArrowRight className="h-4 w-4" />
                  </Button>
                )}
                {currentStep === 4 && (
                  <Button onClick={() => navigate('/')} className="gap-2">
                    Go to Dashboard <ArrowRight className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        <p className="text-center text-xs text-muted-foreground mt-4">
          You can always return to this setup wizard from Settings
        </p>
      </div>
    </div>
  );
}
