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

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public route */}
          <Route path="/login" element={<Login />} />

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
            <Route path="notifications" element={<Notifications />} />
            <Route path="settings" element={<Settings />} />
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
  );
}

export default App;
