import { useState, type FormEvent } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '@/lib/auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

// Forge Cyber Defense logo for login page
function ForgeLoginLogo() {
  return (
    <img
      src="/forge-logo-800.png"
      alt="Forge Cyber Defense"
      className="mx-auto mb-1 w-48 h-auto"
      draggable={false}
    />
  );
}

export function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [displayName, setDisplayName] = useState('');

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/';

  const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      let isBootstrap = false;
      if (mode === 'register') {
        const regResponse = await fetch(`${API_BASE_URL}/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password, display_name: displayName }),
        });

        if (!regResponse.ok) {
          const regError = await regResponse.json().catch(() => ({ error: 'Registration failed' }));
          throw new Error(regError.error || 'Registration failed');
        }
        const regData = await regResponse.json().catch(() => ({}));
        isBootstrap = regData.is_bootstrap === true;
      }

      await login(email, password);
      // Redirect new bootstrap admin to onboarding wizard
      navigate(isBootstrap ? '/setup' : from, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4" style={{ background: 'linear-gradient(135deg, #060f1a 0%, #091e36 50%, #0F2A4A 100%)' }}>
      <Card className="w-full max-w-md border-navy-700/50" style={{ background: 'rgba(9,30,54,0.9)', backdropFilter: 'blur(20px)' }}>
        <CardHeader className="text-center pb-2 pt-4">
          <ForgeLoginLogo />
          <CardTitle className="text-xl text-white" style={{ fontFamily: 'Sora, Inter, system-ui, sans-serif' }}>
            ForgeScan 360
          </CardTitle>
          <CardDescription className="text-navy-300 text-sm">
            {mode === 'login'
              ? 'Sign in to your account'
              : 'Create your first admin account'}
          </CardDescription>
          <p className="text-[10px] tracking-widest uppercase mt-0.5" style={{ color: '#4b77a9' }}>
            Forge Cyber Defense
          </p>
        </CardHeader>
        <CardContent className="pt-2">
          <form onSubmit={handleSubmit} className="space-y-3">
            {mode === 'register' && (
              <div className="space-y-2">
                <Label htmlFor="displayName">Display Name</Label>
                <Input
                  id="displayName"
                  type="text"
                  placeholder="Admin User"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  required
                  disabled={loading}
                />
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="admin@forgecyberdefense.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                disabled={loading}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="Min 8 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={8}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                disabled={loading}
              />
            </div>

            {error && (
              <div className="rounded-md bg-destructive/10 px-4 py-3 text-sm text-destructive">
                {error}
              </div>
            )}

            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? (
                <span className="flex items-center gap-2">
                  <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                  {mode === 'login' ? 'Signing in...' : 'Creating account...'}
                </span>
              ) : (
                mode === 'login' ? 'Sign In' : 'Create Account'
              )}
            </Button>

            <div className="text-center">
              <button
                type="button"
                className="text-sm text-muted-foreground hover:text-teal-400 transition-colors"
                onClick={() => {
                  setMode(mode === 'login' ? 'register' : 'login');
                  setError('');
                }}
              >
                {mode === 'login'
                  ? 'First time? Create admin account'
                  : 'Already have an account? Sign in'}
              </button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
