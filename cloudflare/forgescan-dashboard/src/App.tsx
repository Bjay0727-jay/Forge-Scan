import { Suspense, lazy, type ComponentType } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from '@/components/auth/AuthProvider';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { Layout } from '@/components/layout/Layout';
import { Login } from '@/pages/Login';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { LoadingState } from '@/components/LoadingState';
import { ToastProvider } from '@/components/ui/toast';

/**
 * Wrap a named-export page module in React.lazy.
 * Pages export `export function Foo() {}`, so we adapt the module
 * shape to the default-export contract React.lazy expects.
 */
function lazyPage<K extends string, M extends Record<K, ComponentType<unknown>>>(
  loader: () => Promise<M>,
  exportName: K,
) {
  return lazy(() =>
    loader().then((mod) => ({ default: mod[exportName] })),
  );
}

const Dashboard       = lazyPage(() => import('@/pages/Dashboard'),       'Dashboard');
const Assets          = lazyPage(() => import('@/pages/Assets'),          'Assets');
const Findings        = lazyPage(() => import('@/pages/Findings'),        'Findings');
const Scans           = lazyPage(() => import('@/pages/Scans'),           'Scans');
const Import          = lazyPage(() => import('@/pages/Import'),          'Import');
const Settings        = lazyPage(() => import('@/pages/Settings'),        'Settings');
const UserManagement  = lazyPage(() => import('@/pages/UserManagement'),  'UserManagement');
const Vulnerabilities = lazyPage(() => import('@/pages/Vulnerabilities'), 'Vulnerabilities');
const Scanners        = lazyPage(() => import('@/pages/Scanners'),        'Scanners');
const Integrations    = lazyPage(() => import('@/pages/Integrations'),    'Integrations');
const Notifications   = lazyPage(() => import('@/pages/Notifications'),   'Notifications');
const Compliance      = lazyPage(() => import('@/pages/Compliance'),      'Compliance');
const Reports         = lazyPage(() => import('@/pages/Reports'),         'Reports');
const RedOps          = lazyPage(() => import('@/pages/RedOps'),          'RedOps');
const SOC             = lazyPage(() => import('@/pages/SOC'),             'SOC');
const MSSPPortal      = lazyPage(() => import('@/pages/MSSPPortal'),      'MSSPPortal');
const Onboarding      = lazyPage(() => import('@/pages/Onboarding'),      'Onboarding');
const Containers      = lazyPage(() => import('@/pages/Containers'),      'Containers');
const CodeScan        = lazyPage(() => import('@/pages/CodeScan'),        'CodeScan');
const Playbooks       = lazyPage(() => import('@/pages/Playbooks'),       'Playbooks');
const ThreatIntel     = lazyPage(() => import('@/pages/ThreatIntel'),     'ThreatIntel');
const DesignSystem    = lazyPage(() => import('@/pages/DesignSystem'),    'DesignSystem');

function PageBoundary({ children }: { children: React.ReactNode }) {
  return (
    <ErrorBoundary>
      <Suspense fallback={<LoadingState />}>{children}</Suspense>
    </ErrorBoundary>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <AuthProvider>
          <ToastProvider>
            <Routes>
              {/* Public route */}
              <Route path="/login" element={<Login />} />

              {/* Onboarding wizard (protected but outside Layout) */}
              <Route
                path="/setup"
                element={
                  <ProtectedRoute>
                    <PageBoundary><Onboarding /></PageBoundary>
                  </ProtectedRoute>
                }
              />

              {/* Protected routes */}
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <Layout />
                  </ProtectedRoute>
                }
              >
                <Route index               element={<PageBoundary><Dashboard /></PageBoundary>} />
                <Route path="assets"       element={<PageBoundary><Assets /></PageBoundary>} />
                <Route path="findings"     element={<PageBoundary><Findings /></PageBoundary>} />
                <Route path="scans"        element={<PageBoundary><Scans /></PageBoundary>} />
                <Route path="import"       element={<PageBoundary><Import /></PageBoundary>} />
                <Route path="vulnerabilities" element={<PageBoundary><Vulnerabilities /></PageBoundary>} />
                <Route path="integrations" element={<PageBoundary><Integrations /></PageBoundary>} />
                <Route path="compliance"   element={<PageBoundary><Compliance /></PageBoundary>} />
                <Route path="reports"      element={<PageBoundary><Reports /></PageBoundary>} />
                <Route path="notifications"element={<PageBoundary><Notifications /></PageBoundary>} />
                <Route path="redops"       element={<PageBoundary><RedOps /></PageBoundary>} />
                <Route path="soc"          element={<PageBoundary><SOC /></PageBoundary>} />
                <Route path="containers"   element={<PageBoundary><Containers /></PageBoundary>} />
                <Route path="codescan"     element={<PageBoundary><CodeScan /></PageBoundary>} />
                <Route path="playbooks"    element={<PageBoundary><Playbooks /></PageBoundary>} />
                <Route path="threat-intel" element={<PageBoundary><ThreatIntel /></PageBoundary>} />
                <Route path="design-system"element={<PageBoundary><DesignSystem /></PageBoundary>} />
                <Route path="settings"     element={<PageBoundary><Settings /></PageBoundary>} />
                <Route
                  path="admin/mssp"
                  element={
                    <ProtectedRoute requiredRoles={['platform_admin']}>
                      <PageBoundary><MSSPPortal /></PageBoundary>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="admin/scanners"
                  element={
                    <ProtectedRoute requiredRoles={['platform_admin']}>
                      <PageBoundary><Scanners /></PageBoundary>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="admin/users"
                  element={
                    <ProtectedRoute requiredRoles={['platform_admin']}>
                      <PageBoundary><UserManagement /></PageBoundary>
                    </ProtectedRoute>
                  }
                />
              </Route>
            </Routes>
          </ToastProvider>
        </AuthProvider>
      </BrowserRouter>
    </ErrorBoundary>
  );
}

export default App;
