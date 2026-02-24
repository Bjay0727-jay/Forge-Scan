import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from '@/components/auth/AuthProvider';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { Layout } from '@/components/layout/Layout';
import { Login } from '@/pages/Login';
import { Dashboard } from '@/pages/Dashboard';
import { Assets } from '@/pages/Assets';
import { Findings } from '@/pages/Findings';
import { Scans } from '@/pages/Scans';
import { Import } from '@/pages/Import';
import { Settings } from '@/pages/Settings';
import { UserManagement } from '@/pages/UserManagement';
import { Vulnerabilities } from '@/pages/Vulnerabilities';
import { Scanners } from '@/pages/Scanners';
import { Integrations } from '@/pages/Integrations';
import { Notifications } from '@/pages/Notifications';
import { Compliance } from '@/pages/Compliance';
import { Reports } from '@/pages/Reports';
import { RedOps } from '@/pages/RedOps';
import { SOC } from '@/pages/SOC';
import { MSSPPortal } from '@/pages/MSSPPortal';
import { Onboarding } from '@/pages/Onboarding';
import { Containers } from '@/pages/Containers';
import { CodeScan } from '@/pages/CodeScan';
import { Playbooks } from '@/pages/Playbooks';
import { ThreatIntel } from '@/pages/ThreatIntel';
import { ErrorBoundary } from '@/components/ErrorBoundary';

function App() {
  return (
    <ErrorBoundary>
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public route */}
          <Route path="/login" element={<Login />} />

          {/* Onboarding wizard (protected but outside Layout) */}
          <Route
            path="/setup"
            element={
              <ProtectedRoute>
                <Onboarding />
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
            <Route index element={<Dashboard />} />
            <Route path="assets" element={<Assets />} />
            <Route path="findings" element={<Findings />} />
            <Route path="scans" element={<Scans />} />
            <Route path="import" element={<Import />} />
            <Route path="vulnerabilities" element={<Vulnerabilities />} />
            <Route path="integrations" element={<Integrations />} />
            <Route path="compliance" element={<Compliance />} />
            <Route path="reports" element={<Reports />} />
            <Route path="notifications" element={<Notifications />} />
            <Route path="redops" element={<RedOps />} />
            <Route path="soc" element={<SOC />} />
            <Route path="containers" element={<Containers />} />
            <Route path="codescan" element={<CodeScan />} />
            <Route path="playbooks" element={<Playbooks />} />
            <Route path="threat-intel" element={<ThreatIntel />} />
            <Route path="settings" element={<Settings />} />
            <Route
              path="admin/mssp"
              element={
                <ProtectedRoute requiredRoles={['platform_admin']}>
                  <MSSPPortal />
                </ProtectedRoute>
              }
            />
            <Route
              path="admin/scanners"
              element={
                <ProtectedRoute requiredRoles={['platform_admin']}>
                  <Scanners />
                </ProtectedRoute>
              }
            />
            <Route
              path="admin/users"
              element={
                <ProtectedRoute requiredRoles={['platform_admin']}>
                  <UserManagement />
                </ProtectedRoute>
              }
            />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
    </ErrorBoundary>
  );
}

export default App;
