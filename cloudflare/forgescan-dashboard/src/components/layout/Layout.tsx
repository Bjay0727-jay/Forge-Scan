import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TooltipProvider } from '@/components/ui/tooltip';
import { ErrorBoundary } from '@/components/ErrorBoundary';

export function Layout() {
  return (
    <TooltipProvider>
      <div className="flex h-screen bg-background">
        <Sidebar />
        <main className="flex-1 overflow-auto">
          <div className="container py-4">
            <ErrorBoundary>
              <Outlet />
            </ErrorBoundary>
          </div>
        </main>
      </div>
    </TooltipProvider>
  );
}
