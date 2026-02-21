import { useState, useEffect } from 'react';
import { Users, Plus, Edit, UserX, UserCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

interface UserRecord {
  id: string;
  email: string;
  display_name: string;
  role: string;
  is_active: number;
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
}

const ROLES = [
  { value: 'platform_admin', label: 'Platform Admin' },
  { value: 'scan_admin', label: 'Scan Admin' },
  { value: 'vuln_manager', label: 'Vulnerability Manager' },
  { value: 'remediation_owner', label: 'Remediation Owner' },
  { value: 'auditor', label: 'Auditor' },
];

function getAuthHeaders() {
  const token = localStorage.getItem('forgescan_token');
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
}

const roleBadgeVariant = (role: string) => {
  switch (role) {
    case 'platform_admin': return 'destructive' as const;
    case 'scan_admin': return 'default' as const;
    case 'vuln_manager': return 'secondary' as const;
    default: return 'outline' as const;
  }
};

export function UserManagement() {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<UserRecord | null>(null);
  const [error, setError] = useState('');

  // Create form
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');
  const [newRole, setNewRole] = useState('auditor');
  const [createLoading, setCreateLoading] = useState(false);

  // Edit form
  const [editRole, setEditRole] = useState('');
  const [editDisplayName, setEditDisplayName] = useState('');

  useEffect(() => {
    loadUsers();
  }, []);

  async function loadUsers() {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/auth/users?page_size=100`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setUsers(data.items || []);
      }
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }

  async function handleCreate() {
    setError('');
    setCreateLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/auth/users`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          email: newEmail,
          password: newPassword,
          display_name: newDisplayName,
          role: newRole,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'Failed to create user' }));
        throw new Error(err.error);
      }

      setCreateOpen(false);
      setNewEmail('');
      setNewPassword('');
      setNewDisplayName('');
      setNewRole('auditor');
      loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create user');
    } finally {
      setCreateLoading(false);
    }
  }

  async function handleUpdate() {
    if (!editUser) return;
    try {
      await fetch(`${API_BASE_URL}/auth/users/${editUser.id}`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify({ display_name: editDisplayName, role: editRole }),
      });
      setEditUser(null);
      loadUsers();
    } catch { /* ignore */ }
  }

  async function handleToggleActive(user: UserRecord) {
    try {
      await fetch(`${API_BASE_URL}/auth/users/${user.id}`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify({ is_active: !user.is_active }),
      });
      loadUsers();
    } catch { /* ignore */ }
  }

  function openEdit(user: UserRecord) {
    setEditUser(user);
    setEditRole(user.role);
    setEditDisplayName(user.display_name);
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Users className="h-8 w-8" /> User Management
          </h1>
          <p className="text-muted-foreground mt-1">Manage platform users and their roles</p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> Add User
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Users ({users.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-muted-foreground">Loading users...</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Login</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell className="font-medium">{u.display_name}</TableCell>
                    <TableCell>{u.email}</TableCell>
                    <TableCell>
                      <Badge variant={roleBadgeVariant(u.role)}>
                        {ROLES.find(r => r.value === u.role)?.label || u.role}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={u.is_active ? 'default' : 'secondary'}>
                        {u.is_active ? 'Active' : 'Inactive'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : 'Never'}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="sm" onClick={() => openEdit(u)}>
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => handleToggleActive(u)}>
                          {u.is_active ? (
                            <UserX className="h-4 w-4 text-destructive" />
                          ) : (
                            <UserCheck className="h-4 w-4 text-green-400" />
                          )}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create User Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add User</DialogTitle>
            <DialogDescription>Create a new platform user</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Display Name</Label>
              <Input value={newDisplayName} onChange={(e) => setNewDisplayName(e.target.value)} placeholder="Jane Smith" />
            </div>
            <div className="space-y-2">
              <Label>Email</Label>
              <Input type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} placeholder="jane@company.com" />
            </div>
            <div className="space-y-2">
              <Label>Password</Label>
              <Input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="Min 8 characters" minLength={8} />
            </div>
            <div className="space-y-2">
              <Label>Role</Label>
              <Select value={newRole} onValueChange={setNewRole}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ROLES.map((r) => (
                    <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button onClick={handleCreate} disabled={createLoading || !newEmail || !newPassword || !newDisplayName}>
              {createLoading ? 'Creating...' : 'Create User'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit User Dialog */}
      <Dialog open={!!editUser} onOpenChange={(open) => !open && setEditUser(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit User</DialogTitle>
            <DialogDescription>Update user details for {editUser?.email}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Display Name</Label>
              <Input value={editDisplayName} onChange={(e) => setEditDisplayName(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Role</Label>
              <Select value={editRole} onValueChange={setEditRole}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ROLES.map((r) => (
                    <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditUser(null)}>Cancel</Button>
            <Button onClick={handleUpdate}>Save Changes</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
