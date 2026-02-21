import { useState, useEffect, type FormEvent } from 'react';
import { useAuth } from '@/lib/auth';
import { Key, Lock, Trash2, Plus, Copy } from 'lucide-react';
import { ConfirmBanner } from '@/components/ConfirmBanner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  last_used_at: string | null;
  expires_at: string | null;
  is_active: number;
  created_at: string;
}

function getAuthHeaders() {
  const token = localStorage.getItem('forgescan_token');
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
}

export function Settings() {
  const { user } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState('');
  const [passwordLoading, setPasswordLoading] = useState(false);

  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [newKeyName, setNewKeyName] = useState('');
  const [showNewKey, setShowNewKey] = useState<string | null>(null);
  const [keyDialogOpen, setKeyDialogOpen] = useState(false);
  const [keyLoading, setKeyLoading] = useState(false);
  const [deleteKeyConfirm, setDeleteKeyConfirm] = useState<{ id: string; name: string } | null>(null);

  useEffect(() => {
    loadApiKeys();
  }, []);

  async function loadApiKeys() {
    try {
      const res = await fetch(`${API_BASE_URL}/auth/api-keys`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setApiKeys(data.items || []);
      }
    } catch { /* ignore */ }
  }

  async function handlePasswordChange(e: FormEvent) {
    e.preventDefault();
    setPasswordError('');
    setPasswordSuccess('');

    if (newPassword !== confirmPassword) {
      setPasswordError('New passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      setPasswordError('New password must be at least 8 characters');
      return;
    }

    setPasswordLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/auth/password`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'Failed to change password' }));
        throw new Error(err.error);
      }

      setPasswordSuccess('Password changed successfully. Please log in again.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setPasswordError(err instanceof Error ? err.message : 'Failed to change password');
    } finally {
      setPasswordLoading(false);
    }
  }

  async function handleCreateKey() {
    if (!newKeyName.trim()) return;
    setKeyLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/auth/api-keys`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ name: newKeyName }),
      });

      if (!res.ok) throw new Error('Failed to create API key');

      const data = await res.json();
      setShowNewKey(data.key);
      setNewKeyName('');
      loadApiKeys();
    } catch { /* ignore */ } finally {
      setKeyLoading(false);
    }
  }

  async function handleDeleteKey(id: string) {
    try {
      await fetch(`${API_BASE_URL}/auth/api-keys/${id}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      setDeleteKeyConfirm(null);
      loadApiKeys();
    } catch { /* ignore */ }
  }

  const roleBadgeVariant = (role: string) => {
    switch (role) {
      case 'platform_admin': return 'destructive' as const;
      case 'scan_admin': return 'default' as const;
      default: return 'secondary' as const;
    }
  };

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-3xl font-bold">Settings</h1>

      {/* Profile Card */}
      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>Your account information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-muted-foreground">Display Name</Label>
              <p className="font-medium">{user?.display_name}</p>
            </div>
            <div>
              <Label className="text-muted-foreground">Email</Label>
              <p className="font-medium">{user?.email}</p>
            </div>
            <div>
              <Label className="text-muted-foreground">Role</Label>
              <div className="mt-1">
                <Badge variant={roleBadgeVariant(user?.role || '')}>
                  {user?.role?.replace('_', ' ')}
                </Badge>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Change Password */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5" /> Change Password
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handlePasswordChange} className="space-y-4 max-w-md">
            <div className="space-y-2">
              <Label htmlFor="currentPw">Current Password</Label>
              <Input id="currentPw" type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="newPw">New Password</Label>
              <Input id="newPw" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required minLength={8} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="confirmPw">Confirm New Password</Label>
              <Input id="confirmPw" type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required minLength={8} />
            </div>
            {passwordError && <p className="text-sm text-destructive">{passwordError}</p>}
            {passwordSuccess && <p className="text-sm text-green-400">{passwordSuccess}</p>}
            <Button type="submit" disabled={passwordLoading}>
              {passwordLoading ? 'Changing...' : 'Change Password'}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* API Keys */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" /> API Keys
            </CardTitle>
            <CardDescription>Manage API keys for programmatic access</CardDescription>
          </div>
          <Button size="sm" onClick={() => setKeyDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" /> New Key
          </Button>
        </CardHeader>
        <CardContent>
          {showNewKey && (
            <div className="mb-4 rounded-md border border-green-500/20 bg-green-500/10 p-4">
              <p className="mb-2 text-sm font-medium text-green-400">New API Key (save it now - it won't be shown again):</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 rounded bg-muted px-3 py-2 text-sm font-mono">{showNewKey}</code>
                <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(showNewKey)}>
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
              <Button variant="ghost" size="sm" className="mt-2" onClick={() => setShowNewKey(null)}>Dismiss</Button>
            </div>
          )}

          {deleteKeyConfirm && (
            <ConfirmBanner
              title="Delete API Key"
              description={`Are you sure you want to delete "${deleteKeyConfirm.name}"? Any systems using this key will lose access.`}
              confirmLabel="Delete"
              onConfirm={() => handleDeleteKey(deleteKeyConfirm.id)}
              onCancel={() => setDeleteKeyConfirm(null)}
              variant="destructive"
            />
          )}

          {apiKeys.length === 0 ? (
            <p className="text-sm text-muted-foreground">No API keys yet.</p>
          ) : (
            <div className="space-y-2">
              {apiKeys.map((key) => (
                <div key={key.id} className="flex items-center justify-between rounded-lg border p-3">
                  <div>
                    <p className="font-medium">{key.name}</p>
                    <p className="text-sm text-muted-foreground">
                      {key.key_prefix}... | Created {new Date(key.created_at).toLocaleDateString()}
                      {key.last_used_at && ` | Last used ${new Date(key.last_used_at).toLocaleDateString()}`}
                    </p>
                  </div>
                  <Button variant="ghost" size="sm" onClick={() => setDeleteKeyConfirm({ id: key.id, name: key.name })}>
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Key Dialog */}
      <Dialog open={keyDialogOpen} onOpenChange={setKeyDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create API Key</DialogTitle>
            <DialogDescription>Give your key a descriptive name</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="keyName">Key Name</Label>
              <Input id="keyName" placeholder="e.g., CI/CD Pipeline" value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setKeyDialogOpen(false)}>Cancel</Button>
            <Button onClick={() => { handleCreateKey(); setKeyDialogOpen(false); }} disabled={keyLoading || !newKeyName.trim()}>
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
