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
  Settings as SettingsIcon,
  Users,
  LogOut,
  Crosshair,
  Shield,
  Rocket,
  Building2,
  Box,
  Code,
  Workflow,
  Globe,
  Palette,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth, hasRole } from '@/lib/auth';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

interface NavItem {
  name: string;
  href: string;
  icon: LucideIcon;
  end?: boolean;
}

const mainNavigation: NavItem[] = [
  { name: 'Dashboard',      href: '/',              icon: LayoutDashboard, end: true },
  { name: 'Assets',         href: '/assets',        icon: Server },
  { name: 'Findings',       href: '/findings',      icon: AlertTriangle },
  { name: 'Scans',          href: '/scans',         icon: Scan },
  { name: 'RedOps',         href: '/redops',        icon: Crosshair },
  { name: 'ForgeSOC',       href: '/soc',           icon: Shield },
  { name: 'Vulnerabilities',href: '/vulnerabilities',icon: ShieldAlert },
  { name: 'Integrations',   href: '/integrations',  icon: Plug },
  { name: 'Compliance',     href: '/compliance',    icon: ClipboardCheck },
  { name: 'Reports',        href: '/reports',       icon: FileText },
  { name: 'Notifications',  href: '/notifications', icon: Bell },
  { name: 'Containers',     href: '/containers',    icon: Box },
  { name: 'Code Scan',      href: '/codescan',      icon: Code },
  { name: 'Playbooks',      href: '/playbooks',     icon: Workflow },
  { name: 'Threat Intel',   href: '/threat-intel',  icon: Globe },
  { name: 'Import',         href: '/import',        icon: Upload },
];

const bottomNavigation: NavItem[] = [
  { name: 'Getting Started', href: '/setup',         icon: Rocket },
  { name: 'Design System',   href: '/design-system', icon: Palette },
  { name: 'Settings',        href: '/settings',      icon: SettingsIcon },
];

const adminNavigation: NavItem[] = [
  { name: 'MSSP Portal', href: '/admin/mssp',     icon: Building2 },
  { name: 'Scanners',    href: '/admin/scanners', icon: Cpu },
  { name: 'Users',       href: '/admin/users',    icon: Users },
];

const ROLE_BADGE: Record<string, string> = {
  platform_admin: 'border-teal-500/30 bg-teal-500/15 text-teal-400',
  scan_admin:     'border-navy-300/30 bg-navy-500/15 text-navy-300',
};

const railLink = (
  isActive: boolean,
): React.CSSProperties => ({
  background: isActive ? 'rgba(13,148,136,0.15)' : 'transparent',
  color: isActive ? 'var(--forge-teal-400)' : 'var(--forge-sidebar-text)',
  border: isActive
    ? '1px solid rgba(13,148,136,0.20)'
    : '1px solid transparent',
});

function RailLink({ item }: { item: NavItem }) {
  return (
    <NavLink
      to={item.href}
      end={item.end}
      className={({ isActive }) =>
        cn(
          'flex items-center gap-2.5 rounded-lg px-3 py-1.5 text-sm font-medium',
          'transition-colors duration-forge-fast ease-forge-out',
          isActive ? 'text-foreground' : 'hover:text-foreground',
        )
      }
      style={({ isActive }) => railLink(isActive)}
    >
      <item.icon className="h-4 w-4 flex-shrink-0" strokeWidth={1.5} aria-hidden />
      <span className="truncate">{item.name}</span>
    </NavLink>
  );
}

export function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <aside
      aria-label="Primary"
      className="flex h-full w-64 flex-col"
      style={{ background: 'var(--forge-sidebar-bg)' }}
    >
      {/* Brand Header — horizontal lockup + product eyebrow */}
      <div
        className="flex flex-col items-center justify-center px-2 pt-3 pb-3"
        style={{ borderBottom: '1px solid var(--forge-card-border)' }}
      >
        <img
          src="/forge-logo-400.png"
          alt="Forge Cyber Defense"
          className="w-44 h-auto"
          draggable={false}
        />
        <span
          className="text-[11px] font-semibold tracking-eyebrow uppercase -mt-1 font-heading"
          style={{ color: 'var(--forge-teal-400)' }}
        >
          ForgeScan
        </span>
      </div>

      {/* Main Navigation */}
      <nav
        aria-label="Main navigation"
        className="flex-1 space-y-0.5 px-3 py-2 overflow-y-auto"
      >
        {mainNavigation.map((item) => (
          <RailLink key={item.name} item={item} />
        ))}

        {hasRole(user, 'platform_admin') && (
          <>
            <div
              className="my-2 mx-3"
              style={{ borderTop: '1px solid var(--forge-card-border)' }}
            />
            <p
              className="px-3 mb-1 text-[10px] font-semibold uppercase tracking-widest"
              style={{ color: 'var(--forge-sidebar-text-muted)' }}
            >
              Admin
            </p>
            {adminNavigation.map((item) => (
              <RailLink key={item.name} item={item} />
            ))}
          </>
        )}
      </nav>

      {/* Bottom Section */}
      <div
        className="p-2 space-y-1.5"
        style={{ borderTop: '1px solid var(--forge-card-border)' }}
      >
        {bottomNavigation.map((item) => (
          <RailLink key={item.name} item={item} />
        ))}

        {user && (
          <div
            className="rounded-lg p-2"
            style={{
              background: 'var(--forge-card-bg)',
              border: '1px solid var(--forge-card-border)',
            }}
          >
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0 flex-1">
                <p className="truncate text-[13px] font-medium text-foreground">
                  {user.display_name}
                </p>
                <p
                  className="truncate text-[11px]"
                  style={{ color: 'var(--forge-sidebar-text-muted)' }}
                >
                  {user.email}
                </p>
                <Badge
                  className={cn(
                    'mt-1 text-[10px] border',
                    ROLE_BADGE[user.role] ??
                      'border-navy-400/20 bg-navy-600/20 text-navy-300',
                  )}
                >
                  {user.role.replace('_', ' ')}
                </Badge>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleLogout}
                title="Sign out"
                aria-label="Sign out"
                className="hover:bg-white/[0.06]"
                style={{ color: 'var(--forge-sidebar-text-muted)' }}
              >
                <LogOut className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}

        <p
          className="text-center text-[9px] tracking-widest pt-1"
          style={{ color: 'var(--forge-navy-500)' }}
        >
          FORGE CYBER DEFENSE
        </p>
      </div>
    </aside>
  );
}
