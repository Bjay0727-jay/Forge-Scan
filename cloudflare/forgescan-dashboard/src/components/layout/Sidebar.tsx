import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Server,
  AlertTriangle,
  Scan,
  Upload,
  Shield,
  ShieldAlert,
  Cpu,
  Plug,
  Bell,
  ClipboardCheck,
  FileText,
  Settings,
  Users,
  LogOut,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth, hasRole } from '@/lib/auth';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

const mainNavigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Assets', href: '/assets', icon: Server },
  { name: 'Findings', href: '/findings', icon: AlertTriangle },
  { name: 'Scans', href: '/scans', icon: Scan },
  { name: 'Vulnerabilities', href: '/vulnerabilities', icon: ShieldAlert },
  { name: 'Integrations', href: '/integrations', icon: Plug },
  { name: 'Compliance', href: '/compliance', icon: ClipboardCheck },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Notifications', href: '/notifications', icon: Bell },
  { name: 'Import', href: '/import', icon: Upload },
];

const bottomNavigation = [
  { name: 'Settings', href: '/settings', icon: Settings },
];

const adminNavigation = [
  { name: 'Scanners', href: '/admin/scanners', icon: Cpu },
  { name: 'Users', href: '/admin/users', icon: Users },
];

export function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const roleBadgeVariant = (role: string) => {
    switch (role) {
      case 'platform_admin': return 'destructive' as const;
      case 'scan_admin': return 'default' as const;
      default: return 'secondary' as const;
    }
  };

  return (
    <div className="flex h-full w-64 flex-col border-r bg-card">
      <div className="flex h-16 items-center gap-2 border-b px-6">
        <Shield className="h-8 w-8 text-primary" />
        <span className="text-xl font-bold">ForgeScan</span>
      </div>

      {/* Main Navigation */}
      <nav className="flex-1 space-y-1 p-4">
        {mainNavigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            end={item.href === '/'}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
              )
            }
          >
            <item.icon className="h-5 w-5" />
            {item.name}
          </NavLink>
        ))}

        {/* Admin Section */}
        {hasRole(user, 'platform_admin') && (
          <>
            <div className="my-3 border-t" />
            <p className="px-3 text-xs font-semibold uppercase text-muted-foreground">Admin</p>
            {adminNavigation.map((item) => (
              <NavLink
                key={item.name}
                to={item.href}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                  )
                }
              >
                <item.icon className="h-5 w-5" />
                {item.name}
              </NavLink>
            ))}
          </>
        )}
      </nav>

      {/* Bottom Section */}
      <div className="border-t p-4 space-y-2">
        {bottomNavigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
              )
            }
          >
            <item.icon className="h-5 w-5" />
            {item.name}
          </NavLink>
        ))}

        {/* User Profile */}
        {user && (
          <div className="rounded-lg bg-muted p-3">
            <div className="flex items-center justify-between">
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{user.display_name}</p>
                <p className="truncate text-xs text-muted-foreground">{user.email}</p>
                <Badge variant={roleBadgeVariant(user.role)} className="mt-1 text-[10px]">
                  {user.role.replace('_', ' ')}
                </Badge>
              </div>
              <Button variant="ghost" size="sm" onClick={handleLogout} title="Sign out">
                <LogOut className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
