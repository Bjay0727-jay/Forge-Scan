import React from 'react';
import { render, type RenderOptions } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { AuthContext, type AuthContextType, type User } from '@/lib/auth';

// Default mock auth context values
const defaultUser: User = {
  id: 'test-user-1',
  email: 'test@forgescan.dev',
  display_name: 'Test User',
  role: 'platform_admin',
};

const defaultAuthContext: AuthContextType = {
  user: defaultUser,
  token: 'mock-jwt-token',
  isAuthenticated: true,
  isLoading: false,
  login: async () => {},
  logout: async () => {},
  refreshUser: async () => {},
};

interface RenderWithProvidersOptions extends Omit<RenderOptions, 'wrapper'> {
  authContext?: Partial<AuthContextType>;
}

/**
 * Render a component wrapped with all necessary providers:
 * - BrowserRouter (for routing)
 * - AuthContext.Provider (for auth)
 */
export function renderWithProviders(
  ui: React.ReactElement,
  options: RenderWithProvidersOptions = {}
) {
  const { authContext: authOverrides, ...renderOptions } = options;
  const authContext = { ...defaultAuthContext, ...authOverrides };

  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <BrowserRouter>
        <AuthContext.Provider value={authContext}>
          {children}
        </AuthContext.Provider>
      </BrowserRouter>
    );
  }

  return {
    ...render(ui, { wrapper: Wrapper, ...renderOptions }),
    authContext,
  };
}

export { defaultUser, defaultAuthContext };
