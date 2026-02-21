import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Server,
  AlertTriangle,
  Scan,
  Upload,
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

  const roleBadgeColor = (role: string) => {
    switch (role) {
      case 'platform_admin': return 'bg-teal-500/20 text-teal-400 border-teal-500/30';
      case 'scan_admin': return 'bg-navy-500/20 text-navy-300 border-navy-400/30';
      default: return 'bg-navy-600/20 text-navy-300 border-navy-400/20';
    }
  };

  return (
    <div className="flex h-full w-64 flex-col" style={{ background: '#060f1a' }}>
      {/* Brand Header */}
      <div className="flex flex-col items-center justify-center px-2 pt-4 pb-3" style={{ borderBottom: '1px solid rgba(75,119,169,0.2)' }}>
        <img
          src="/forge-logo-400.png"
          alt="Forge Cyber Defense"
          className="w-60 h-auto"
          draggable={false}
        />
        <span className="text-[13px] font-semibold tracking-[0.35em] uppercase -mt-1" style={{ color: '#14b8a6', fontFamily: 'Sora, Inter, system-ui, sans-serif' }}>
          ForgeScan 360
        </span>
      </div>

      {/* Main Navigation */}
      <nav className="flex-1 space-y-0.5 px-3 py-4 overflow-y-auto">
        {mainNavigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            end={item.href === '/'}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-150',
                isActive
                  ? 'text-white'
                  : 'hover:text-white'
              )
            }
            style={({ isActive }) => ({
              background: isActive ? 'rgba(13,148,136,0.15)' : 'transparent',
              color: isActive ? '#14b8a6' : '#6b8fb9',
              border: isActive ? '1px solid rgba(13,148,136,0.2)' : '1px solid transparent',
            })}
          >
            <item.icon className="h-[18px] w-[18px] flex-shrink-0" />
            {item.name}
          </NavLink>
        ))}

        {/* Admin Section */}
        {hasRole(user, 'platform_admin') && (
          <>
            <div className="my-3 mx-3" style={{ borderTop: '1px solid rgba(75,119,169,0.2)' }} />
            <p className="px-3 mb-1 text-[10px] font-semibold uppercase tracking-widest" style={{ color: '#4b77a9' }}>
              Admin
            </p>
            {adminNavigation.map((item) => (
              <NavLink
                key={item.name}
                to={item.href}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-150',
                    isActive
                      ? 'text-white'
                      : 'hover:text-white'
                  )
                }
                style={({ isActive }) => ({
                  background: isActive ? 'rgba(13,148,136,0.15)' : 'transparent',
                  color: isActive ? '#14b8a6' : '#6b8fb9',
                  border: isActive ? '1px solid rgba(13,148,136,0.2)' : '1px solid transparent',
                })}
              >
                <item.icon className="h-[18px] w-[18px] flex-shrink-0" />
                {item.name}
              </NavLink>
            ))}
          </>
        )}
      </nav>

      {/* Bottom Section */}
      <div className="p-3 space-y-2" style={{ borderTop: '1px solid rgba(75,119,169,0.2)' }}>
        {bottomNavigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-150',
                isActive
                  ? 'text-white'
                  : 'hover:text-white'
              )
            }
            style={({ isActive }) => ({
              background: isActive ? 'rgba(13,148,136,0.15)' : 'transparent',
              color: isActive ? '#14b8a6' : '#6b8fb9',
              border: isActive ? '1px solid rgba(13,148,136,0.2)' : '1px solid transparent',
            })}
          >
            <item.icon className="h-[18px] w-[18px] flex-shrink-0" />
            {item.name}
          </NavLink>
        ))}

        {/* User Profile */}
        {user && (
          <div className="rounded-lg p-3" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(75,119,169,0.2)' }}>
            <div className="flex items-center justify-between">
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium text-white">{user.display_name}</p>
                <p className="truncate text-xs" style={{ color: '#4b77a9' }}>{user.email}</p>
                <Badge className={cn('mt-1 text-[10px] border', roleBadgeColor(user.role))}>
                  {user.role.replace('_', ' ')}
                </Badge>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleLogout}
                title="Sign out"
                className="hover:bg-white/[0.06]"
                style={{ color: '#4b77a9' }}
              >
                <LogOut className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}

        {/* Forge Cyber Defense footer text */}
        <p className="text-center text-[9px] tracking-wider pt-1" style={{ color: '#1a3a5c' }}>
          FORGE CYBER DEFENSE
        </p>
      </div>
    </div>
  );
}
